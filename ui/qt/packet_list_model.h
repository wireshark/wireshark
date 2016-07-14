/* packet_list_model.h
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef PACKET_LIST_MODEL_H
#define PACKET_LIST_MODEL_H

#include <config.h>

#include <stdio.h>

#include <glib.h>

#include <epan/packet.h>

#include <QAbstractItemModel>
#include <QFont>
#include <QVector>

#include "packet_list_record.h"

#include "cfile.h"

class QElapsedTimer;

class PacketListModel : public QAbstractItemModel
{
    Q_OBJECT
public:
    explicit PacketListModel(QObject *parent = 0, capture_file *cf = NULL);
    ~PacketListModel();
    void setCaptureFile(capture_file *cf);
    QModelIndex index(int row, int column,
                      const QModelIndex & = QModelIndex()) const;
    QModelIndex parent(const QModelIndex &) const;
    int packetNumberToRow(int packet_num) const;
    guint recreateVisibleRows();
    void clear();

    int rowCount(const QModelIndex &parent = QModelIndex()) const;
    int columnCount(const QModelIndex & = QModelIndex()) const;
    QVariant data(const QModelIndex &d_index, int role) const;
    QVariant headerData(int section, Qt::Orientation orientation,
                        int role = Qt::DisplayRole | Qt::ToolTipRole) const;

    gint appendPacket(frame_data *fdata);
    frame_data *getRowFdata(int row);
    void ensureRowColorized(int row);
    int visibleIndexOf(frame_data *fdata) const;
    void resetColumns();
    void resetColorized();
    void toggleFrameMark(const QModelIndex &fm_index);
    void setDisplayedFrameMark(gboolean set);
    void toggleFrameIgnore(const QModelIndex &i_index);
    void setDisplayedFrameIgnore(gboolean set);
    void toggleFrameRefTime(const QModelIndex &rt_index);
    void unsetAllFrameRefTime();
    void applyTimeShift();

    void setMaximiumRowHeight(int height);

signals:
    void goToPacket(int);
    void maxLineCountChanged(const QModelIndex &ih_index) const;
    void itemHeightChanged(const QModelIndex &ih_index);
    void pushBusyStatus(const QString &status);
    void popBusyStatus();

    void pushProgressStatus(const QString &status, bool animate, bool terminate_is_stop, gboolean *stop_flag);
    void updateProgressStatus(int value);
    void popProgressStatus();

public slots:
    void sort(int column, Qt::SortOrder order = Qt::AscendingOrder);
    void flushVisibleRows();
    void dissectIdle(bool reset = false);

private:
    capture_file *cap_file_;
    QList<QString> col_names_;
    QVector<PacketListRecord *> physical_rows_;
    QVector<PacketListRecord *> visible_rows_;
    QVector<PacketListRecord *> new_visible_rows_;
    QVector<int> number_to_row_;

    int max_row_height_; // px
    int max_line_count_;

    static int sort_column_;
    static int text_sort_column_;
    static Qt::SortOrder sort_order_;
    static capture_file *sort_cap_file_;
    static bool recordLessThan(PacketListRecord *r1, PacketListRecord *r2);

    QElapsedTimer *idle_dissection_timer_;
    int idle_dissection_row_;


private slots:
    void emitItemHeightChanged(const QModelIndex &ih_index);
};

#endif // PACKET_LIST_MODEL_H

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
