/* packet_list_model.h
 *
 * $Id$
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

#include "config.h"

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
                      const QModelIndex &parent = QModelIndex()) const;
    QModelIndex parent(const QModelIndex &index) const;
    guint recreateVisibleRows();
    void setColorEnabled(bool enable_color);
    void clear();

    int rowCount(const QModelIndex &parent = QModelIndex()) const;
    int columnCount(const QModelIndex &parent = QModelIndex()) const;
    QVariant data(const QModelIndex &index, int role) const;
    QVariant headerData(int section, Qt::Orientation orientation,
                             int role = Qt::DisplayRole) const;

    gint appendPacket(frame_data *fdata);
    frame_data *getRowFdata(int row);
    int visibleIndexOf(frame_data *fdata) const;


signals:

public slots:

private:
    capture_file *cap_file_;
    QList<QString> col_names_;
    QVector<PacketListRecord *> visible_rows_;
    QVector<PacketListRecord *> physical_rows_;
    QFont pl_font_;

    int header_height_;
    bool enable_color_;
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
