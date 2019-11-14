/*
 * credentials_model.h
 *
 * Copyright 2019 - Dario Lombardo <lomato@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CREDENTIALS_MODELS_H
#define CREDENTIALS_MODELS_H

#include <QAbstractListModel>
#include <QList>

#include <epan/tap.h>
#include <capture_file.h>
#include <ui/tap-credentials.h>

class CredentialsModel : public QAbstractListModel
{
    Q_OBJECT
public:
    CredentialsModel(QObject *parent);
    virtual int rowCount(const QModelIndex &parent = QModelIndex()) const ;
    virtual int columnCount(const QModelIndex &parent = QModelIndex()) const;
    virtual QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const;
    virtual QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const;

    void addRecord(tap_credential_t* rec);
    void clear();

    enum {
        COL_NUM,
        COL_PROTO,
        COL_USERNAME,
        COL_INFO
    };

    enum {
        ColumnHFID = Qt::UserRole + 1
    };

private:
    QList<tap_credential_t*> credentials_;

};

#endif // CREDENTIALS_MODELS_H

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
