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

/**
 * @brief A table model managing a list of exportable objects extracted from network traffic.
 */
class ExportObjectModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new ExportObjectModel.
     * @param eo Pointer to the registered export object type.
     * @param parent The parent QObject.
     */
    ExportObjectModel(register_eo_t* eo, QObject *parent);

    /**
     * @brief Destroys the ExportObjectModel.
     */
    virtual ~ExportObjectModel();

    /**
     * @brief Enumerates the columns for the export object model.
     */
    enum ExportObjectColumn {
        colPacket = 0,      /**< Packet number column. */
        colHostname,        /**< Hostname column. */
        colContent,         /**< Content type column. */
        colSize,            /**< Size of the object column. */
        colFilename,        /**< Filename column. */
        colExportObjectMax  /**< End of columns marker. */
    };

    /**
     * @brief Adds a new export object entry to the model.
     * @param entry Pointer to the export object entry.
     */
    void addObjectEntry(export_object_entry_t *entry);

    /**
     * @brief Retrieves the export object entry at a specific row.
     * @param row The row index.
     * @return Pointer to the export object entry.
     */
    export_object_entry_t *objectEntry(int row);

    /**
     * @brief Resets and clears all object entries from the model.
     */
    void resetObjects();

    /**
     * @brief Saves a specific entry to a file.
     * @param index The model index of the entry to save.
     * @param filename The destination filename.
     * @return True if saved successfully, false otherwise.
     */
    bool saveEntry(const QModelIndex &index, QString filename);

    /**
     * @brief Saves multiple entries to a directory.
     * @param indices The list of model indices to save.
     * @param path The destination directory path.
     */
    void saveEntries(const QModelIndexList &indices, QString path);

    /**
     * @brief Saves all entries in the model to a directory.
     * @param path The destination directory path.
     */
    void saveAllEntries(QString path);

    /**
     * @brief Retrieves the name of the tap listener.
     * @return The tap listener name string.
     */
    const char* getTapListenerName();

    /**
     * @brief Retrieves the tap data pointer.
     * @return Pointer to the tap data.
     */
    void* getTapData();

    /**
     * @brief Retrieves the callback function used for processing tap packets.
     * @return The tap packet callback function pointer.
     */
    tap_packet_cb getTapPacketFunc();

    /**
     * @brief Static callback used to reset the tap data.
     * @param tapdata Pointer to the tap data to reset.
     */
    static void resetTap(void *tapdata);

    /**
     * @brief Removes the associated tap listener.
     */
    void removeTap();

    /**
     * @brief Retrieves data from the model for a given index and role.
     * @param index The model index.
     * @param role The data role requested.
     * @return The data associated with the index and role.
     */
    QVariant data(const QModelIndex &index, int role) const;

    /**
     * @brief Retrieves the header data for a specific section and role.
     * @param section The column or row section.
     * @param orientation The orientation of the header.
     * @param role The data role requested (defaults to Qt::DisplayRole).
     * @return The header data.
     */
    QVariant headerData(int section, Qt::Orientation orientation,
                        int role = Qt::DisplayRole) const;

    /**
     * @brief Returns the number of rows under a given parent.
     * @param parent The parent model index (defaults to an invalid QModelIndex).
     * @return The number of rows.
     */
    int rowCount(const QModelIndex &parent = QModelIndex()) const;

    /**
     * @brief Returns the number of columns under a given parent.
     * @param parent The parent model index (defaults to an invalid QModelIndex).
     * @return The number of columns.
     */
    int columnCount(const QModelIndex &parent = QModelIndex()) const;

private:
    /** List storing variants representing the export objects. */
    QList<QVariant> objects_;
    QSet<ExportObjectEntry> object_set_;

    /** The core list structure holding the export objects. */
    export_object_list_t export_object_list_;

    /** GUI specific context data for the export object list. */
    export_object_list_gui_t eo_gui_data_;

    /** Pointer to the registered export object type definition. */
    register_eo_t* eo_;
};

/**
 * @brief A proxy model used for sorting and filtering export objects.
 */
class ExportObjectProxyModel : public QSortFilterProxyModel
{
public:

    /**
     * @brief Constructs a new ExportObjectProxyModel.
     * @param parent The parent QObject, defaults to Q_NULLPTR.
     */
    explicit ExportObjectProxyModel(QObject * parent = Q_NULLPTR);

    /**
     * @brief Sets the filter string used for matching content types.
     * @param contentFilter The content type filter string.
     */
    void setContentFilterString(QString contentFilter);

    /**
     * @brief Sets the text filter string used for general searching.
     * @param textFilter The general text filter string.
     */
    void setTextFilterString(QString textFilter);
    void setUniqueFilter(bool unique);

protected:
    /**
     * @brief Compares two source indices to determine their sort order.
     * @param source_left The first source index.
     * @param source_right The second source index.
     * @return True if the left item should appear before the right item.
     */
    bool lessThan(const QModelIndex &source_left, const QModelIndex &source_right) const;

    /**
     * @brief Determines whether a row from the source model matches the active filters and should be displayed.
     * @param source_row The row in the source model.
     * @param source_parent The parent index in the source model.
     * @return True if the row is accepted, false otherwise.
     */
    bool filterAcceptsRow(int source_row, const QModelIndex &source_parent) const;

private:
    /** The active content type filter string. */
    QString contentFilter_;

    /** The active general text filter string. */
    QString textFilter_;
    bool uniqueFilter_;

};

#endif // EXPORT_OBJECTS_MODEL_H
