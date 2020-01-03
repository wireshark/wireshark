/* pref_module_view.cpp
 * Tree view of preference module data.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "pref_module_view.h"
#include <ui/qt/models/pref_models.h>

#include <QHeaderView>

PrefModuleTreeView::PrefModuleTreeView(QWidget *parent) : QTreeView(parent),
    appearanceName_(PrefsModel::typeToString(PrefsModel::Appearance))
{
}

void PrefModuleTreeView::setPane(const QString module_name)
{
    QModelIndex newIndex, modelIndex, appearanceIndex, protocolIndex, statIndex;
    QString moduleName;
    int row;

    //look for the pane name in the main tree before trying children
    for (row = 0; row < model()->rowCount(); row++)
    {
        modelIndex = model()->index(row, ModulePrefsModel::colName);
        moduleName = model()->data(modelIndex, ModulePrefsModel::ModuleName).toString();

        if (moduleName.compare(appearanceName_) == 0) {
            appearanceIndex = modelIndex;
        } else if (moduleName.compare("Protocols") == 0) {
            protocolIndex = modelIndex;
        } else if (moduleName.compare("Statistics") == 0) {
            statIndex = modelIndex;
        }

        if (moduleName.compare(module_name) == 0) {
            newIndex = modelIndex;
            break;
        }
    }

    //Look through appearance children
    if (!newIndex.isValid()) {
        newIndex = findModule(appearanceIndex, module_name);
    }

    //Look through protocol children
    if (!newIndex.isValid()) {
        newIndex = findModule(protocolIndex, module_name);
    }

    //Look through stat children
    if (!newIndex.isValid()) {
        newIndex = findModule(statIndex, module_name);
    }

    setCurrentIndex(newIndex);
}

QModelIndex PrefModuleTreeView::findModule(QModelIndex& parent, const QString& name)
{
    QModelIndex findIndex, modelIndex;
    QString module_name;

    for (int row = 0; row < model()->rowCount(parent); row++)
    {
        modelIndex = model()->index(row, ModulePrefsModel::colName, parent);
        module_name = model()->data(modelIndex, ModulePrefsModel::ModuleName).toString();
        if (name.compare(module_name) == 0) {
            findIndex = modelIndex;
            break;
        }
        if (model()->rowCount(modelIndex) > 0) {
            findIndex = findModule(modelIndex, name);
            if (findIndex.isValid())
                break;
        }
    }

    return findIndex;
}


void PrefModuleTreeView::currentChanged(const QModelIndex &current, const QModelIndex &previous)
{
    if (current.isValid())
    {
        QString module_name = model()->data(current, ModulePrefsModel::ModuleName).toString();

        emit goToPane(module_name);
    }

    QTreeView::currentChanged(current, previous);
}

/* * Editor modelines
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
