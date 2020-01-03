/* pref_module_view.h
 * Tree view of preference module data.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PREFERENCE_MODULE_VIEW_H
#define PREFERENCE_MODULE_VIEW_H

#include <config.h>
#include <QTreeView>

class PrefModuleTreeView : public QTreeView
{
    Q_OBJECT
public:
    PrefModuleTreeView(QWidget *parent = 0);

    void setPane(const QString module_name);

signals:
    void goToPane(QString module_name);

protected slots:
    void currentChanged(const QModelIndex &current, const QModelIndex &previous);

private:
    QModelIndex findModule(QModelIndex &parent, const QString& name);

    //cache the translation of the module names we check frequently
    QString appearanceName_;
};
#endif // PREFERENCE_MODULE_VIEW_H

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
