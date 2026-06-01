/* display_filter_history_model.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <ui/qt/models/display_filter_history_model.h>

#include <ui/qt/utils/qt_ui_utils.h>
#include "ui/recent.h"
#include "ui/recent_utils.h"

#include <epan/prefs.h>

#include <stdio.h>

#include <QStringList>

// Process-global recent display-filter store, most-recent first. This replaces
// the static QStandardItemModel that used to live in DisplayFilterCombo. It is
// filled at startup by dfilter_recent_add() (called from recent.c, newest
// line first) and updated by addRecent() when a filter is applied.
static QStringList &recentStore()
{
    static QStringList store;
    return store;
}

// Live models, so changes made through the C entry points refresh any open view.
static QList<DisplayFilterHistoryModel *> &liveModels()
{
    static QList<DisplayFilterHistoryModel *> models;
    return models;
}

static void notifyLiveModels()
{
    for (DisplayFilterHistoryModel *model : liveModels())
        model->reload();
}

// C entry points used by recent.c to load and save the recent display filters.
// They were defined in display_filter_combo.cpp; they move here with the store.
extern "C" bool dfilter_recent_add(const char *dftext)
{
    QString filter = QString::fromUtf8(dftext);
    if (filter.isEmpty())
        return true;

    QStringList &store = recentStore();
    store.removeAll(filter);
    // recent.c reads the file newest-first, so appending keeps that order.
    store.append(filter);
    notifyLiveModels();
    return true;
}

extern "C" void dfilter_recent_write_all(FILE *rf)
{
    for (const QString &filter : recentStore()) {
        const QByteArray &line = join_lines(filter).toUtf8();
        if (!line.isEmpty())
            fprintf(rf, RECENT_KEY_DISPLAY_FILTER ": %s\n", line.constData());
    }
}

DisplayFilterHistoryModel::DisplayFilterHistoryModel(QObject *parent) :
    FilterHistoryModel(parent)
{
    liveModels().append(this);
}

DisplayFilterHistoryModel::~DisplayFilterHistoryModel()
{
    liveModels().removeAll(this);
}

int DisplayFilterHistoryModel::rowCount(const QModelIndex &parent) const
{
    if (parent.isValid())
        return 0;
    return static_cast<int>(recentStore().size());
}

QVariant DisplayFilterHistoryModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() >= recentStore().size())
        return QVariant();
    if (role == Qt::DisplayRole || role == Qt::EditRole)
        return recentStore().at(index.row());
    return QVariant();
}

void DisplayFilterHistoryModel::addRecent(const QString &expression)
{
    if (expression.isEmpty())
        return;

    QStringList &store = recentStore();
    store.removeAll(expression);
    store.prepend(expression);

    const int max_entries = prefs.gui_recent_df_entries_max;
    while (max_entries > 0 && store.size() > max_entries)
        store.removeLast();

    notifyLiveModels();
}

void DisplayFilterHistoryModel::reload()
{
    beginResetModel();
    endResetModel();
}
