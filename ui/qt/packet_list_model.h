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

class PacketListModel : public QAbstractItemModel
{
    Q_OBJECT
public:
    explicit PacketListModel(QObject *parent = 0, capture_file *cf = NULL);
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
                             int role = Qt::DisplayRole) const;

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
    void setSizeHintEnabled(bool enable) { size_hint_enabled_ = enable; }

signals:
    void goToPacket(int);
    void itemHeightChanged(const QModelIndex &ih_index) const;
    void pushBusyStatus(const QString &status);
    void popBusyStatus();

    void pushProgressStatus(const QString &status, bool animate, bool terminate_is_stop, gboolean *stop_flag);
    void updateProgressStatus(int value);
    void popProgressStatus();

public slots:
    void setMonospaceFont(const QFont &mono_font, int row_height);
    void sort(int column, Qt::SortOrder order = Qt::AscendingOrder);

private:
    capture_file *cap_file_;
    QFont mono_font_;
    QList<QString> col_names_;
    QVector<PacketListRecord *> visible_rows_;
    QVector<PacketListRecord *> physical_rows_;
    QMap<int, int> number_to_row_;

    bool size_hint_enabled_;
    int row_height_;
    int line_spacing_;

    static int sort_column_;
    static int text_sort_column_;
    static Qt::SortOrder sort_order_;
    static capture_file *sort_cap_file_;
    static bool recordLessThan(PacketListRecord *r1, PacketListRecord *r2);

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
