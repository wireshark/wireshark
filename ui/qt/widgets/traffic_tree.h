/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef TRAFFIC_TREE_H
#define TRAFFIC_TREE_H

#include "config.h"

#include <ui/recent.h>

#include <ui/qt/models/atap_data_model.h>
#include <ui/qt/filter_action.h>

#include <QTreeView>
#include <QMenu>

class TrafficTree : public QTreeView
{
    Q_OBJECT

public:
    /**
     * @brief Type for the selection of export
     * @see copyToClipboard
     */
    typedef enum {
        CLIPBOARD_CSV,  /* export as CSV */
        CLIPBOARD_YAML, /* export as YAML */
        CLIPBOARD_JSON  /* export as JSON */
    } eTrafficTreeClipboard;

    TrafficTree(QString baseName, QWidget *parent = nullptr);

    /**
     * @brief Create a menu containing clipboard copy entries for this tab
     *
     * It will create all entries, including copying the content of the currently selected tab
     * to CSV, YAML and JSON
     *
     * @param parent the parent object or null
     * @return QMenu* the resulting menu or null
     */
    QMenu * createCopyMenu(QWidget * parent = nullptr);

signals:
    void filterAction(QString filter, FilterAction::Action action, FilterAction::ActionType type);

public slots:
    void tapListenerEnabled(bool enable);
    void disableTap();

private:
    bool _tapEnabled;
    int _exportRole;
    bool _saveRaw;
    QString _baseName;

    ATapDataModel * dataModel();

    QMenu * createActionSubMenu(FilterAction::Action cur_action, QModelIndex idx, bool isConversation);
    void copyToClipboard(eTrafficTreeClipboard type);

private slots:
    void customContextMenu(const QPoint &pos);
    void useFilterAction();
    void clipboardAction();
    void resizeAction();
    void toggleSaveRawAction();

};

#endif // TRAFFIC_TREE_H
