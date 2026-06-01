/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DISPLAY_FILTER_ENTRY_H
#define DISPLAY_FILTER_ENTRY_H

#include <ui/qt/widgets/filter_expression_edit.h>

class QDragEnterEvent;
class QDragMoveEvent;
class QDropEvent;
class QContextMenuEvent;

/**
 * @brief Display-filter entry: the FilterExpressionEdit leaf for dfilters.
 *
 * Wires the display validator/completer/history/bookmark backends, runs in
 * explicit-apply mode (Enter or the apply action commits), and translates the
 * base's generic signals to the display-filter vocabulary (filterPackets /
 * showPreferencesDialog) while driving the main-window status bar directly.
 *
 * Adds the display-only affordances the capture leaf does not need: drag-and-drop
 * of display-filter and toolbar mime data, and a context-menu entry for the
 * Display Filter Expression builder.
 *
 * This replaces the DisplayFilterCombo + old DisplayFilterEdit on the main
 * toolbar. The old SyntaxLineEdit-based DisplayFilterEdit still exists for the
 * remaining read-filter / custom-column sites until those are migrated.
 */
class DisplayFilterEntry : public FilterExpressionEdit
{
    Q_OBJECT

public:
    explicit DisplayFilterEntry(QWidget *parent = nullptr);

public slots:
    /** @brief Re-validates the current text (e.g. on preferences change). */
    void recheck();

    /**
     * @brief Reflects whether the last applied filter succeeded; keeps the apply
     *        action disabled while the field already matches the active filter.
     */
    void displayFilterSuccess(bool success);

    /** @brief Sets the field text and focuses it (programmatic filter entry). */
    void setDisplayFilter(QString filter);

    /** @brief Applies the current expression (explicit apply). */
    void applyDisplayFilter();

    /**
     * @brief Validates the current expression.
     * @return false when the syntax is Invalid, true otherwise.
     */
    bool checkDisplayFilter();

signals:
    /** @brief Push a filter-syntax message to the status bar. */
    void pushFilterSyntaxStatus(const QString &msg);
    /** @brief Pop the filter-syntax message from the status bar. */
    void popFilterSyntaxStatus();
    /** @brief Request applying @p new_filter to the packet list. */
    void filterPackets(QString new_filter, bool force);
    /** @brief Request showing a preferences pane. */
    void showPreferencesDialog(QString pane_name);

protected:
    void dragEnterEvent(QDragEnterEvent *event) override;
    void dragMoveEvent(QDragMoveEvent *event) override;
    void dropEvent(QDropEvent *event) override;
    void contextMenuEvent(QContextMenuEvent *event) override;

private:
    void connectToMainWindow();
    void updateStatus(SyntaxState state);
    void createFilterTextDropMenu(QDropEvent *event, bool prepare, QString filterText = QString());
    void displayFilterExpression();

    QString last_applied_; /**< Text of the last successfully applied filter. */
};

#endif // DISPLAY_FILTER_ENTRY_H
