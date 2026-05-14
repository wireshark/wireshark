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
#include <QSet>

typedef struct export_object_list_gui_t {
    class ExportObjectModel *model;
} export_object_list_gui_t;

class ExportObjectEntry
{
public:
    explicit ExportObjectEntry(export_object_entry_t *entry = nullptr) : entry(entry) {}

    bool operator==(const ExportObjectEntry &other) const {
        return eo_entry_equal(entry, other.entry);
    }
#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
    QByteArray Data() const { return entry ? QByteArray::fromRawData(reinterpret_cast<const char*>(entry->payload_data), entry->payload_len) : QByteArray(); }
#else
    QByteArrayView Data() const { return entry ? QByteArrayView(entry->payload_data, entry->payload_len) : QByteArrayView(); }
#endif
    uint32_t PacketNum() const { return entry ? entry->pkt_num : 0; }

private:
    export_object_entry_t *entry;
};

size_t qHash(const ExportObjectEntry& entry, size_t seed = 0);

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

    bool saveEntry(const QModelIndex &index, QString filename);
    void saveEntries(const QModelIndexList &indices, QString path);
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
    QSet<ExportObjectEntry> object_set_;

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
    void setUniqueFilter(bool unique);

protected:
    bool lessThan(const QModelIndex &source_left, const QModelIndex &source_right) const;
    bool filterAcceptsRow(int source_row, const QModelIndex &source_parent) const;

private:
    QString contentFilter_;
    QString textFilter_;
    bool uniqueFilter_;

};

#endif // EXPORT_OBJECTS_MODEL_H
