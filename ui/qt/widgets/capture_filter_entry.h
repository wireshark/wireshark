/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CAPTURE_FILTER_ENTRY_H
#define CAPTURE_FILTER_ENTRY_H

#include <ui/qt/widgets/filter_expression_edit.h>

#include <QPair>

/**
 * @brief Capture-filter entry: the FilterExpressionEdit leaf for libpcap filters.
 *
 * Wires the capture validator/completer/history/bookmark backends, runs in
 * implicit-apply mode, and translates the base's generic signals to the
 * capture-filter vocabulary (captureFilterSyntaxChanged / captureFilterChanged /
 * startCapture / addBookmark).
 *
 * This is the capture-filter widget used everywhere capture filters are entered
 * (welcome page and Capture Options main field); the old SyntaxLineEdit-based
 * CaptureFilterEdit and the CaptureFilterCombo wrapper have been removed. Inline
 * table-cell editors (per-interface rows, the saved-filter manager) use a plain
 * FilterEdit with a capture validator instead, as they need no in-line chrome.
 */
class CaptureFilterEntry : public FilterExpressionEdit
{
    Q_OBJECT

public:
    explicit CaptureFilterEntry(QWidget *parent = nullptr);

    /**
     * @brief Sets the conflict state shown when selected interfaces disagree on
     *        their capture filter (adjusts placeholder text and tooltip).
     */
    void setConflict(bool conflict = false);

    /**
     * @brief The capture filter common to the selected interfaces.
     * @return (filter, conflict): empty/false if none selected, (filter, false)
     *         if all agree, (empty, true) if they differ.
     */
    static QPair<const QString, bool> getSelectedFilter();

public slots:
    /** @brief Re-validates the current text (e.g. when the interface selection changes). */
    void recheck();

signals:
    /** @brief Capture-filter validity changed (from the base validityChanged). */
    void captureFilterSyntaxChanged(bool valid);
    /** @brief Capture-filter text changed (from the base textChangedExpr). */
    void captureFilterChanged(const QString &filter);
    /** @brief Capture requested via Enter (from the base applied). */
    void startCapture();
    /** @brief Bookmark requested for the current expression. */
    void addBookmark(const QString &filter);

private:
    QString placeholder_text_; /**< Cached placeholder for the (non-)conflict state. */
};

#endif // CAPTURE_FILTER_ENTRY_H
