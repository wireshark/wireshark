/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CAPTURE_FILTER_BOOKMARK_MODEL_H
#define CAPTURE_FILTER_BOOKMARK_MODEL_H

#include <ui/qt/models/bookmark_model.h>

class FilterListModel;

/**
 * @brief Saved-capture-filter bookmarks backed by FilterListModel(Capture).
 *
 * Presents the saved capture filters as a flat list with ExpressionRole and
 * NameRole, persisting through the underlying FilterListModel (the same store
 * the Capture Filters manager edits). contains() drives the bookmark menu's
 * "remove current" enablement.
 */
class CaptureFilterBookmarkModel : public BookmarkModel
{
    Q_OBJECT

public:
    explicit CaptureFilterBookmarkModel(QObject *parent = nullptr);

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;

    bool contains(const QString &expression) const override;

    /** @brief Adds a saved filter and persists the list. */
    void addBookmark(const QString &name, const QString &expression);
    /** @brief Removes the saved filter matching @p expression and persists. */
    void removeBookmark(const QString &expression);

public slots:
    /** @brief Reloads from the saved-filters store (e.g. on external change). */
    void reload();

private:
    FilterListModel *list_; /**< Underlying capture saved-filter store. */
};

#endif // CAPTURE_FILTER_BOOKMARK_MODEL_H
