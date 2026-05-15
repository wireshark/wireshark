/** @file
 *
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

/**
 * @brief A tree view for displaying and navigating preference modules.
 */
class PrefModuleTreeView : public QTreeView
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a new PrefModuleTreeView object.
     * @param parent The parent widget.
     */
    PrefModuleTreeView(QWidget *parent = 0);

    /**
     * @brief Sets the active preference pane to the specified module.
     * @param module_name The name of the module to set as the active pane.
     */
    void setPane(const QString module_name);

signals:
    /**
     * @brief Signal emitted to navigate to a specific preference pane.
     * @param module_name The name of the target module.
     */
    void goToPane(QString module_name);

protected slots:
    /**
     * @brief Handles the event when the current item in the tree view changes.
     * @param current The new current model index.
     * @param previous The previous current model index.
     */
    void currentChanged(const QModelIndex &current, const QModelIndex &previous);

private:
    /**
     * @brief Finds a module by name within a given parent index.
     * @param parent The parent model index to search within.
     * @param name The name of the module to find.
     * @return The model index of the found module, or an invalid index if not found.
     */
    QModelIndex findModule(QModelIndex &parent, const QString& name);

    /** @brief Cached translation of the appearance module name checked frequently. */
    QString appearanceName_;
};
#endif // PREFERENCE_MODULE_VIEW_H
