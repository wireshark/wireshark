/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef BOOKMARK_MODEL_H
#define BOOKMARK_MODEL_H

#include <QAbstractListModel>
#include <QString>

/**
 * @brief Abstract list model of saved ("bookmarked") filter expressions.
 *
 * Separate store and model from the recent history. Each entry carries at least
 * an expression and a display name, exposed through ExpressionRole and NameRole.
 * DisplayRole/EditRole return the expression, so typeahead completion offers the
 * value; the bookmark menu reads ExpressionRole/NameRole explicitly. The model
 * owns load/save/persistence.
 *
 * The bookmark model is widget-owned: FilterExpressionEdit deletes it with
 * itself. Concrete subclasses (DisplayFilterBookmarkModel, CaptureFilterBookmarkModel)
 * back this with their existing saved-filter stores.
 */
class BookmarkModel : public QAbstractListModel
{
    Q_OBJECT

public:
    /** @brief Item-data roles exposed by every bookmark model. */
    enum Roles {
        ExpressionRole = Qt::UserRole + 1, /**< The filter expression text. */
        NameRole                           /**< The human-readable display name. */
    };

    explicit BookmarkModel(QObject *parent = nullptr);

    /**
     * @brief Returns true when @p expression exactly matches a saved entry.
     *
     * Drives the enablement of the bookmark menu's "remove current" action,
     * centralising logic that the old edits duplicated inside checkFilter().
     */
    virtual bool contains(const QString &expression) const = 0;
};

#endif // BOOKMARK_MODEL_H
