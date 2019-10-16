/* uat_model.h
 * Data model for UAT records.
 *
 * Copyright 2016 Peter Wu <peter@lekensteyn.nl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef UAT_MODEL_H
#define UAT_MODEL_H

#include <config.h>
#include <glib.h>

#include <QAbstractItemModel>
#include <QList>
#include <QMap>
#include <epan/uat-int.h>

class UatModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    UatModel(QObject *parent, uat_t *uat = 0);
    UatModel(QObject *parent, QString tableName);

    Qt::ItemFlags flags(const QModelIndex &index) const;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const;
    QVariant headerData(int section, Qt::Orientation orientation,
                        int role = Qt::DisplayRole) const;
    int rowCount(const QModelIndex &parent = QModelIndex()) const;
    int columnCount(const QModelIndex &parent = QModelIndex()) const;

    bool setData(const QModelIndex &index, const QVariant &value, int role = Qt::EditRole);

    bool insertRows(int row, int count, const QModelIndex &parent = QModelIndex());
    bool removeRows(int row, int count, const QModelIndex &parent = QModelIndex());

    bool copyRow(int dst_row, int src_row);
    bool moveRow(int src_row, int dst_row);

    void reloadUat();
    bool hasErrors() const;
    void clearAll();

    /**
     * If the UAT has changed, save the contents to file and invoke the UAT
     * post_update_cb.
     *
     * @param error An error while saving changes, if any.
     * @return true if anything changed, false otherwise.
     */
    bool applyChanges(QString &error);

    /**
     * Undo any changes to the UAT.
     *
     * @param error An error while restoring the original UAT, if any.
     * @return true if anything changed, false otherwise.
     */
    bool revertChanges(QString &error);

    QModelIndex findRowForColumnContent(QVariant columnContent, int columnToCheckAgainst, int role = Qt::DisplayRole);

private:
    bool checkField(int row, int col, char **error) const;
    QList<int> checkRow(int row);
    void loadUat(uat_t * uat = 0);

    epan_uat *uat_;
    QList<bool> dirty_records;
    QList<QMap<int, QString> > record_errors;
};
#endif // UAT_MODEL_H
