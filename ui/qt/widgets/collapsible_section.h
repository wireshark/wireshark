/* collapsible_section.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef COLLAPSIBLE_SECTION_H
#define COLLAPSIBLE_SECTION_H

#include <QFont>
#include <QFrame>
#include <QToolButton>
#include <QVBoxLayout>
#include <QWidget>

class QHBoxLayout;

/**
 * @brief A collapsible section widget for use in a QSplitter.
 *
 * This widget displays a clickable header that toggles the visibility
 * of the content area. When collapsed, the widget shrinks to just the
 * header height. When expanded, it can be resized via the parent splitter.
 * Multiple CollapsibleSection widgets can be independently expanded or
 * collapsed.
 */
class CollapsibleSection : public QWidget
{
    Q_OBJECT

  public:
    /**
     * @brief Construct a collapsible section.
     * @param title The title displayed in the header.
     * @param parent Optional parent widget.
     */
    explicit CollapsibleSection(const QString &title = QString(),
                                QWidget *parent = nullptr);

    /**
     * @brief Set the content widget for this section.
     * @param contentWidget The widget to display when expanded.
     *
     * The section takes ownership of the widget.
     */
    void setContentWidget(QWidget *contentWidget);

    /**
     * @brief Set the expanded state of the section.
     * @param expanded True to expand, false to collapse.
     */
    void setExpanded(bool expanded);

    /**
     * @brief Check if the section is currently expanded.
     * @return True if expanded, false if collapsed.
     */
    bool isExpanded() const;

    /**
     * @brief Set the title text.
     * @param title The new title.
     */
    void setTitle(const QString &title);

    /**
     * @brief Get the header height (for splitter sizing when collapsed).
     * @return The height of the header in pixels.
     */
    int headerHeight() const;

    /**
     * @brief Height of the title / toggle control (single header line).
     * @return Pixels, at least 1. Used to size header trailing controls to match.
     */
    int titleButtonHeight() const;

    /**
     * @brief Font used for the section title (bold application font).
     */
    QFont titleButtonFont() const;

    /**
     * @brief Set an optional widget in the header row after the horizontal
     *        rule (order: title, rule, trailing). Pass @c nullptr to clear.
     *        The widget is sized to the title line height. The section
     *        takes ownership of @a widget.
     * @param widget The widget to show, or @c nullptr.
     */
    void setHeaderTrailingWidget(QWidget *widget);

  signals:
    /**
     * @brief Emitted when the section is toggled.
     * @param expanded True if now expanded, false if collapsed.
     */
    void toggled(bool expanded);

  private slots:
    /**
     * @brief Toggle the content area visibility and emit the toggled signal.
     * @param checked True if the toggle button is checked (expanded), false otherwise.
     */
    void onToggle(bool checked);

  private:
    QToolButton *toggleButton;
    QFrame *headerLine;
    QHBoxLayout *headerLayout_ = nullptr;
    /** Wraps headerLayout_ with a fixed height so the row cannot grow when
     *  toggleButton->sizeHint() fluctuates by 1-2px on arrowType change. */
    QWidget *headerContainer_ = nullptr;
    QWidget *contentArea;
    QVBoxLayout *mainLayout;
    /** Non-null if setHeaderTrailingWidget; owned as child, cleared on replace. */
    QWidget *headerTrailingWidget_ = nullptr;
    int savedHeight;
    /** Cached header row height, captured once from toggleButton->sizeHint()
     *  at construction. The platform style's sizeFromContents(CT_ToolButton)
     *  consults opt.arrowType, so a live sizeHint() varies by 1-2px between
     *  RightArrow and DownArrow; using a cached value keeps headerHeight()
     *  and titleButtonHeight() stable across toggles. */
    int titleH_ = 0;
};

#endif // COLLAPSIBLE_SECTION_H
