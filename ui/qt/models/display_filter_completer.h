/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DISPLAY_FILTER_COMPLETER_H
#define DISPLAY_FILTER_COMPLETER_H

#include <ui/qt/models/filter_completer.h>

class QStringListModel;

/**
 * @brief FilterCompleter for Wireshark display filters.
 *
 * Unlike the capture completer's fixed primitive list, the display field set is
 * rebuilt on each completion pass from the protocol registry: protocol filter
 * names, their fields, and display-filter functions, restricted to the token
 * under the cursor and only when a field is grammatical at that position. The
 * dynamic list is exposed through fieldsModel() so the host can merge it with
 * recent history and bookmarks via QConcatenateTablesProxyModel.
 *
 * The rebuild hooks into splitPath(): QCompleter calls it to derive the match
 * prefix immediately before filtering the model, which is exactly when the field
 * list must reflect the current token and preamble.
 */
class DisplayFilterCompleter : public FilterCompleter
{
    Q_OBJECT

public:
    explicit DisplayFilterCompleter(QObject *parent = nullptr);

    /**
     * @brief The dynamic protocol-field model, owned by this completer. The host
     *        adds it as a source of the merged completion model alongside
     *        history and bookmarks.
     */
    QStringListModel *fieldsModel() const { return fields_; }

    /**
     * @brief Returns the token under the cursor and, as a side effect, rebuilds
     *        fieldsModel() for the current token/preamble.
     */
    QStringList splitPath(const QString &path) const override;

private:
    /** @brief Repopulates fields_ with protocol/field/function matches. */
    void rebuildFields(const QString &field_word, const QString &preamble) const;

    QStringListModel *fields_; /**< Owned dynamic field list model. */
};

#endif // DISPLAY_FILTER_COMPLETER_H
