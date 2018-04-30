/* packet_list_record.h
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

#include <epan/column-info.h>
#include <epan/packet.h>

#include <QByteArray>
#include <QList>
#include <QVariant>

struct conversation;
struct _GStringChunk;

class ColumnTextList;

class PacketListRecord
{
public:
    PacketListRecord(frame_data *frameData);

    // Allocate our records using wmem.
    static void *operator new(size_t size);
    static void operator delete(void *) {}

    // Return the string value for a column. Data is cached if possible.
    const QByteArray columnString(capture_file *cap_file, int column, bool colorized = false);
    frame_data *frameData() const { return fdata_; }
    // packet_list->col_to_text in gtk/packet_list_store.c
    static int textColumn(int column) { return cinfo_column_.value(column, -1); }
    bool colorized() { return colorized_; }
    struct conversation *conversation() { return conv_; }

    int columnTextSize(const char *str);
    static void invalidateAllRecords() { col_data_ver_++; }
    static void resetColumns(column_info *cinfo);
    void resetColorized();
    inline int lineCount() { return lines_; }
    inline int lineCountChanged() { return line_count_changed_; }

    static void clearStringPool();

private:
    /** The column text for some columns */
    ColumnTextList *col_text_;

    frame_data *fdata_;
    int lines_;
    bool line_count_changed_;
    static QMap<int, int> cinfo_column_;

    /** Data versions. Used to invalidate col_text_ */
    static unsigned col_data_ver_;
    unsigned data_ver_;
    /** Has this record been colorized? */
    bool colorized_;

    /** Conversation. Used by RelatedPacketDelegate */
    struct conversation *conv_;

    void dissect(capture_file *cap_file, bool dissect_color = false);
    void cacheColumnStrings(column_info *cinfo);

    static struct _GStringChunk *string_pool_;

};

#endif // PACKET_LIST_RECORD_H

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
