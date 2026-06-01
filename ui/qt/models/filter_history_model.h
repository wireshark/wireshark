/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FILTER_HISTORY_MODEL_H
#define FILTER_HISTORY_MODEL_H

#include <QAbstractListModel>
#include <QString>

/**
 * @brief Abstract list model of recently applied filter expressions.
 *
 * The recent-history store is process/global-scoped (today fed by the C
 * dfilter_recent_add path). The host injects a concrete model and retains
 * ownership of it: FilterExpressionEdit holds a non-owning reference and must
 * not delete it.
 *
 * Most-recent entries appear first (row 0). Apply commits an expression here via
 * addRecent(), which deduplicates and moves the entry to the front, bounding the
 * list. Concrete subclasses (DisplayFilterHistoryModel, CaptureFilterHistoryModel)
 * back this with their respective recent stores.
 */
class FilterHistoryModel : public QAbstractListModel
{
    Q_OBJECT

public:
    explicit FilterHistoryModel(QObject *parent = nullptr);

    /**
     * @brief Commits @p expression to the recent list.
     *
     * Implementations deduplicate, move the entry to the front, and bound the
     * list length.
     */
    virtual void addRecent(const QString &expression) = 0;
};

#endif // FILTER_HISTORY_MODEL_H
