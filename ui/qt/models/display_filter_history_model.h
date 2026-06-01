/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DISPLAY_FILTER_HISTORY_MODEL_H
#define DISPLAY_FILTER_HISTORY_MODEL_H

#include <ui/qt/models/filter_history_model.h>

/**
 * @brief Recent-display-filter history.
 *
 * Unlike the capture side, there is no recent_*_dfilter GList in the C core: the
 * recent display-filter list was owned by the old DisplayFilterCombo. This model
 * now owns that process-global store. It is populated at startup by the C entry
 * point dfilter_recent_add() (called from recent.c as the recent file is
 * read) and persisted by dfilter_recent_write_all(); both live in the .cpp
 * so deleting the combo does not break recent-file load/save.
 *
 * Entries are most-recent first (row 0). addRecent() deduplicates, moves to the
 * front, and bounds the list to gui_recent_df_entries_max.
 */
class DisplayFilterHistoryModel : public FilterHistoryModel
{
    Q_OBJECT

public:
    explicit DisplayFilterHistoryModel(QObject *parent = nullptr);
    ~DisplayFilterHistoryModel() override;

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;

    void addRecent(const QString &expression) override;

public slots:
    /** @brief Re-reads the shared store (e.g. on preferences change). */
    void reload();
};

#endif // DISPLAY_FILTER_HISTORY_MODEL_H
