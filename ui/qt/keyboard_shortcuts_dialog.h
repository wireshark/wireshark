/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef KEYBOARD_SHORTCUTS_DIALOG_H
#define KEYBOARD_SHORTCUTS_DIALOG_H

#include "geometry_state_dialog.h"

#include <ui/qt/models/astringlist_list_model.h>

#include <QPersistentModelIndex>
#include <QPoint>
#include <QString>

class QShowEvent;

namespace Ui {
class KeyboardShortcutsDialog;
}

class ShortcutListModel : public AStringListListModel
{
    Q_OBJECT
public:
    explicit ShortcutListModel(QObject *parent = Q_NULLPTR);

protected:
    QStringList headerColumns() const override;
};

class KeyboardShortcutsDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    explicit KeyboardShortcutsDialog(QWidget *parent = 0);
    ~KeyboardShortcutsDialog();

protected:
    void showEvent(QShowEvent *event) override;

private slots:
    void showCopyMenu(const QPoint &pos);
    void copyColumnSelection();
    void copyRowSelection();
    void printShortcuts();

private:
    void copySelection(bool copy_row);
    QString buildShortcutsHtml() const;
    QString applicationVersionLabel() const;

    Ui::KeyboardShortcutsDialog *ui;
    ShortcutListModel *shortcut_model_;
    AStringListListSortFilterProxyModel *shortcut_proxy_model_;
    QPersistentModelIndex context_menu_index_;
};

#endif // KEYBOARD_SHORTCUTS_DIALOG_H
