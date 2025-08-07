/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_LIST_MODEL_H
#define PACKET_LIST_MODEL_H

#include <config.h>

#include <stdio.h>

#include <epan/packet.h>

#include <QAbstractItemModel>
#include <QFont>
#include <QVector>

#include <ui/qt/progress_frame.h>

#include "packet_list_record.h"

#include "cfile.h"

class QElapsedTimer;

class PacketListModel : public QAbstractItemModel
{
    Q_OBJECT
public:

    enum {
        HEADER_CAN_DISPLAY_STRINGS = Qt::UserRole,
        HEADER_CAN_DISPLAY_DETAILS,
    };

    explicit PacketListModel(QObject *parent = 0, capture_file *cf = NULL);
    ~PacketListModel();
    void setCaptureFile(capture_file *cf);
    QModelIndex index(int row, int column,
                      const QModelIndex & = QModelIndex()) const;
    QModelIndex parent(const QModelIndex &) const;
    int packetNumberToRow(int packet_num) const;
    unsigned recreateVisibleRows();
    inline void needRecreateVisibleRows() { need_recreate_visible_rows_ = !physical_rows_.isEmpty(); }
    void clear();

    int rowCount(const QModelIndex &parent = QModelIndex()) const;
    int columnCount(const QModelIndex & = QModelIndex()) const;
    QVariant data(const QModelIndex &d_index, int role) const;
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const;

    int appendPacket(frame_data *fdata);
    frame_data *getRowFdata(QModelIndex idx) const;
    frame_data *getRowFdata(int row) const;
    void ensureRowColorized(int row);
    int visibleIndexOf(const frame_data *fdata) const;
    /**
     * @brief Invalidate any cached column strings.
     */
    void invalidateAllColumnStrings();
    /**
     * @brief Rebuild columns from settings.
     */
    void resetColumns();
    void resetColorized();
    void toggleFrameMark(const QModelIndexList &indeces);
    void setDisplayedFrameMark(bool set);
    void toggleFrameIgnore(const QModelIndexList &indeces);
    void setDisplayedFrameIgnore(bool set);
    void toggleFrameRefTime(const QModelIndex &rt_index);
    void unsetAllFrameRefTime();
    void addFrameComment(const QModelIndexList &indices, const QByteArray &comment);
    void setFrameComment(const QModelIndex &index, const QByteArray &comment, unsigned c_number);
    void deleteFrameComments(const QModelIndexList &indices);
    void deleteAllFrameComments();

signals:
    void packetAppended(capture_file *cap_file, frame_data *fdata, qsizetype row);
    void goToPacket(int);

    void bgColorizationProgress(int first, int last);

public slots:
    void sort(int column, Qt::SortOrder order = Qt::AscendingOrder);
    void stopSorting();
    void flushVisibleRows();
    void dissectIdle(bool reset = false);

private:
    capture_file *cap_file_;
    QList<QString> col_names_;
    QVector<PacketListRecord *> physical_rows_;
    QVector<PacketListRecord *> visible_rows_;
    QVector<PacketListRecord *> new_visible_rows_;
    QVector<int> number_to_row_;
    bool need_recreate_visible_rows_;

    static int sort_column_;
    static int sort_column_is_numeric_;
    static int text_sort_column_;
    static Qt::SortOrder sort_order_;
    static capture_file *sort_cap_file_;
    static bool recordLessThan(PacketListRecord *r1, PacketListRecord *r2);
    static double parseNumericColumn(const QString &val, bool *ok);

    static bool stop_flag_;
    static ProgressFrame *progress_frame_;
    static double exp_comps_;
    static double comps_;

    QElapsedTimer *idle_dissection_timer_;
    int idle_dissection_row_;

    bool isNumericColumn(int column);
    void updateVisibleRows(PacketListRecord*);
};

#endif // PACKET_LIST_MODEL_H
