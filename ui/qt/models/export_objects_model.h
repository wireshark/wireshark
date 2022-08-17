/** @file
 *
 * Data model for Export Objects.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef EXPORT_OBJECTS_MODEL_H
#define EXPORT_OBJECTS_MODEL_H

#include <config.h>

#include <epan/tap.h>
#include <epan/export_object.h>

#include <QAbstractTableModel>
#include <QSortFilterProxyModel>
#include <QList>

typedef struct export_object_list_gui_t {
    class ExportObjectModel *model;
} export_object_list_gui_t;

class ExportObjectModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    ExportObjectModel(register_eo_t* eo, QObject *parent);
    virtual ~ExportObjectModel();

    enum ExportObjectColumn {
        colPacket = 0,
        colHostname,
        colContent,
        colSize,
        colFilename,
        colExportObjectMax
    };

    void addObjectEntry(export_object_entry_t *entry);
    export_object_entry_t *objectEntry(int row);
    void resetObjects();

    bool saveEntry(QModelIndex &index, QString filename);
    void saveAllEntries(QString path);

    const char* getTapListenerName();
    void* getTapData();
    tap_packet_cb getTapPacketFunc();
    static void resetTap(void *tapdata);
    void removeTap();

    QVariant data(const QModelIndex &index, int role) const;
    QVariant headerData(int section, Qt::Orientation orientation,
                        int role = Qt::DisplayRole) const;
    int rowCount(const QModelIndex &parent = QModelIndex()) const;
    int columnCount(const QModelIndex &parent = QModelIndex()) const;

private:
    QList<QVariant> objects_;

    export_object_list_t export_object_list_;
    export_object_list_gui_t eo_gui_data_;
    register_eo_t* eo_;
};

class ExportObjectProxyModel : public QSortFilterProxyModel
{
public:

    explicit ExportObjectProxyModel(QObject * parent = Q_NULLPTR);

    void setContentFilterString(QString contentFilter);
    void setTextFilterString(QString textFilter);

protected:
    bool lessThan(const QModelIndex &source_left, const QModelIndex &source_right) const;
    bool filterAcceptsRow(int source_row, const QModelIndex &source_parent) const;

private:
    QString contentFilter_;
    QString textFilter_;

};

#endif // EXPORT_OBJECTS_MODEL_H
