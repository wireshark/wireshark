/* capture_filter_history_model.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <ui/qt/models/capture_filter_history_model.h>

#include <ui/qt/utils/qt_ui_utils.h>
#include "ui/recent.h"

CaptureFilterHistoryModel::CaptureFilterHistoryModel(QObject *parent) :
    FilterHistoryModel(parent)
{
    reload();
}

int CaptureFilterHistoryModel::rowCount(const QModelIndex &parent) const
{
    if (parent.isValid())
        return 0;
    return static_cast<int>(entries_.size());
}

QVariant CaptureFilterHistoryModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() >= entries_.size())
        return QVariant();
    if (role == Qt::DisplayRole || role == Qt::EditRole)
        return entries_.at(index.row());
    return QVariant();
}

void CaptureFilterHistoryModel::addRecent(const QString &expression)
{
    if (expression.isEmpty())
        return;
    // recent_add_cfilter() handles dedup + move-to-front + bounding.
    recent_add_cfilter(NULL, expression.toUtf8().constData());
    reload();
}

void CaptureFilterHistoryModel::reload()
{
    beginResetModel();
    entries_.clear();
    GList *cfilter_list = recent_get_cfilter_list(NULL);
    for (GList *li = g_list_first(cfilter_list); li != NULL; li = gxx_list_next(li)) {
        entries_ << QString::fromUtf8(gxx_list_data(const char *, li));
    }
    endResetModel();
}
