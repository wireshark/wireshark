/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef ABOUT_DIALOG_H
#define ABOUT_DIALOG_H

#include "config.h"

#include <ui/qt/models/astringlist_list_model.h>

#include <QDialog>
#include <QAbstractItemModel>
#include <QModelIndex>
#include <QHash>
#include <QString>
#include <QSortFilterProxyModel>

namespace Ui {
class AboutDialog;
}

class AuthorListModel : public AStringListListModel
{
Q_OBJECT

public:
    explicit AuthorListModel(QObject * parent = Q_NULLPTR);
    virtual ~AuthorListModel();

protected:
    virtual QStringList headerColumns() const;

};

class PluginListModel : public AStringListListModel
{
    Q_OBJECT
public:
    explicit PluginListModel(QObject * parent = Q_NULLPTR);

    QStringList typeNames() const;

protected:
    virtual QStringList headerColumns() const;

private:
    QStringList typeNames_;
};

class ShortcutListModel : public AStringListListModel
{
    Q_OBJECT
public:
    explicit ShortcutListModel(QObject * parent = Q_NULLPTR);

protected:
    virtual QStringList headerColumns() const;
};

class FolderListModel : public AStringListListModel
{
    Q_OBJECT
public:
    explicit FolderListModel(QObject * parent = Q_NULLPTR);

protected:
    virtual QStringList headerColumns() const;
};

class AboutDialog : public QDialog
{
    Q_OBJECT

public:
    explicit AboutDialog(QWidget *parent = 0);
    ~AboutDialog();

protected:
    virtual bool event(QEvent *event);
    virtual void showEvent(QShowEvent *);

private:
    void updateWiresharkText();

    Ui::AboutDialog *ui;
    QString script_pattern;
    QString clipboardInfo;

private slots:
    void urlDoubleClicked(const QModelIndex &);
    void handleCopyMenu(QPoint);
    void showInFolderActionTriggered();
    void copyActionTriggered(bool row = false);
    void copyRowActionTriggered();
    void on_tblPlugins_doubleClicked(const QModelIndex &index);
    void on_copyToClipboard_clicked();
};

#endif // ABOUT_DIALOG_H
