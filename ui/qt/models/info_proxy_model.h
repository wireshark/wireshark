/* info_proxy_model.h
 * Proxy model for displaying an info text at the end of any QAbstractListModel
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef INFO_PROXY_MODEL_H
#define INFO_PROXY_MODEL_H

#include <config.h>

#include <QStringList>
#include <QIdentityProxyModel>

class InfoProxyModel : public QIdentityProxyModel
{
    Q_OBJECT

public:
    explicit InfoProxyModel(QObject * parent = 0);
    ~InfoProxyModel();

    virtual int rowCount(const QModelIndex &parent = QModelIndex()) const;
    virtual QVariant data (const QModelIndex &index, int role = Qt::DisplayRole) const;

    virtual Qt::ItemFlags flags(const QModelIndex &index) const;
    virtual QModelIndex index(int row, int column, const QModelIndex &parent = QModelIndex()) const;

    virtual QModelIndex mapToSource(const QModelIndex &proxyIndex) const;
    virtual QModelIndex mapFromSource(const QModelIndex &fromIndex) const;

    void appendInfo(QString info);
    void clearInfos();

    void setColumn(int column);

private:

    int column_;

    QStringList infos_;
};

#endif // INFO_PROXY_MODEL_H

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
