/* pluginifdemo_main.h
 *
 * Author: Roland Knall <rknall@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PLUGINIFDEMO_MAIN_H_
#define PLUGINIFDEMO_MAIN_H_

#include <QWidget>
#include <QDialog>
#include <QAbstractButton>
#include <QListWidget>
#include <QAbstractListModel>
#include <QSortFilterProxyModel>
#include <QStandardItemModel>

#include <epan/plugin_if.h>

namespace Ui {
class PluginIFDemo_Main;
}

class PluginIfType
{
public:
    PluginIfType(const QString &label, const ext_toolbar_item_t &itemType);

    QString label() const;
    ext_toolbar_item_t itemType() const;
private:
    QString m_label;
    ext_toolbar_item_t m_itemType;
};

class PluginIfTypeModel : public QAbstractListModel
{
    Q_OBJECT
public:
    PluginIfTypeModel(QObject * parent = 0);

    void addPluginIfType(const PluginIfType & pluginIfType);

    int rowCount(const QModelIndex & parent = QModelIndex()) const;
    QVariant data(const QModelIndex & idx, int role = Qt::DisplayRole) const;

private:
    QList<PluginIfType> m_pluginIfTypes;

};

class PluginIfTypeSortFilterProxyModel : public QSortFilterProxyModel
{
    Q_OBJECT
public:
    PluginIfTypeSortFilterProxyModel(QObject * parent = 0);

    bool filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const;

    void setFilterElement(ext_toolbar_item_t filterType);

private:
    ext_toolbar_item_t m_filterType;
};

class PluginIFDemo_Main : public QDialog
{
    Q_OBJECT

public:
    explicit PluginIFDemo_Main(QWidget *parent = 0);
    ~PluginIFDemo_Main();

    void setToolbar(ext_toolbar_t * &toolbar);

private slots:
    void on_buttonBox_clicked(QAbstractButton *button);
    void on_btnSendButtonText_clicked();
    void on_btnSendText_clicked();
    void on_btnSendUpdateItem_clicked();
    void on_chkTestCheckbox_stateChanged(int newState);
    void on_tabInterfaceTypes_currentChanged(int newTab);
    void on_btnAddItem_clicked();
    void on_btnRemoveItem_clicked();
    void on_btnSendList_clicked();
    void on_cmbElements_currentTextChanged(const QString & newText);
    void on_lstItems_clicked(const QModelIndex &idx);
    void on_btnEnable_clicked();
    void on_btnDisable_clicked();

    void logChanged(QString message);
    void closeDialog();

private:
    Ui::PluginIFDemo_Main *ui;

    PluginIfTypeModel * sourceModel;
    PluginIfTypeSortFilterProxyModel * proxyModel;
    QStandardItemModel * listModel;
    QStandardItemModel * indexModel;

    ext_toolbar_t * _toolbar;
};


#endif /* PLUGINIFDEMO_MAIN_H_ */

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
