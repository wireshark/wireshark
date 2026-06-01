/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CAPTURE_FILTER_HISTORY_MODEL_H
#define CAPTURE_FILTER_HISTORY_MODEL_H

#include <ui/qt/models/filter_history_model.h>

#include <QStringList>

/**
 * @brief Recent-capture-filter history backed by the global recent store.
 *
 * Reads recent_get_cfilter_list()/recent_add_cfilter() (the global recent store
 * the capture filter dropdown reads), most-recent first. addRecent() commits an
 * applied expression to that store and refreshes.
 */
class CaptureFilterHistoryModel : public FilterHistoryModel
{
    Q_OBJECT

public:
    explicit CaptureFilterHistoryModel(QObject *parent = nullptr);

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;

    void addRecent(const QString &expression) override;

public slots:
    /** @brief Reloads from the global recent store (e.g. on preferences change). */
    void reload();

private:
    QStringList entries_; /**< Cached recent filters, most-recent first. */
};

#endif // CAPTURE_FILTER_HISTORY_MODEL_H
