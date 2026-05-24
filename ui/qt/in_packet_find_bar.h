/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef IN_PACKET_FIND_BAR_H
#define IN_PACKET_FIND_BAR_H

#include <QLabel>
#include <wsutil/utf8_entities.h>
#include "widgets/syntax_line_edit.h"
#include <QModelIndex>
#include <QPropertyAnimation>
#include <QTimer>
#include <QToolButton>
#include <QWidget>

class ProtoTree;

/**
 * @brief Find bar widget for searching within a specific packet's protocol tree.
 */
class InPacketFindBar : public QWidget
{
    Q_OBJECT
    Q_PROPERTY(int barHeight READ barHeight WRITE setBarHeight)

public:
    /**
     * @brief Constructs a new InPacketFindBar object.
     * @param tree The protocol tree to search within.
     * @param parent The parent widget.
     */
    explicit InPacketFindBar(ProtoTree *tree, QWidget *parent = nullptr);

    /**
     * @brief Destroys the InPacketFindBar object.
     */
    ~InPacketFindBar();

    /**
     * @brief Returns the number of currently open instances of the find bar.
     * @return Number of open instances.
     */
    static int openInstances() { return open_instances_; }

    /**
     * @brief Shows the find bar with an animation.
     */
    void showAnimated();

    /**
     * @brief Hides the find bar with an animation.
     */
    void hideAnimated();

    /**
     * @brief Sets focus to the search input field.
     */
    void focusSearchField();

    /**
     * @brief Checks if a specific model index matches the current search criteria.
     * @param model_index The model index to check.
     * @return @c true if the index matches; @c false otherwise.
     */
    bool isMatch(const QModelIndex &model_index) const;

    /**
     * @brief Checks if a specific model index is the currently active/selected match.
     * @param model_index The model index to check.
     * @return @c true if it is the current match; @c false otherwise.
     */
    bool isCurrentMatch(const QModelIndex &model_index) const;

    /**
     * @brief Checks whether the widget is currently operating in dark mode.
     * @return @c true if dark mode is active; @c false otherwise.
     */
    bool isDarkMode() const;

    /**
     * @brief Gets the current height of the animated bar.
     * @return The height in pixels.
     */
    int barHeight() const;

    /**
     * @brief Sets the height of the animated bar.
     * @param h The new height in pixels.
     */
    void setBarHeight(int h);

signals:
    /**
     * @brief Signal emitted when the search matches are updated.
     */
    void matchesChanged();

protected:
    /**
     * @brief Event filter for handling specific widget events.
     * @param obj Object that received the event.
     * @param event The event to process.
     * @return @c true if the event was handled; @c false to pass it on.
     */
    bool eventFilter(QObject *obj, QEvent *event) override;

private slots:
    /**
     * @brief Slot triggered when the search text changes.
     * @param text The new search text.
     */
    void onTextChanged(const QString &text);

    /**
     * @brief Slot to perform the actual search operation.
     */
    void performSearch();

    /**
     * @brief Slot to navigate to the next match.
     */
    void findNext();

    /**
     * @brief Slot to navigate to the previous match.
     */
    void findPrevious();

    /**
     * @brief Slot to close the find bar.
     */
    void closeBar();

    /**
     * @brief Slot triggered when search toggle options (case, regex, word) change.
     */
    void onToggleChanged();

private:
    /**
     * @brief Updates the internal list of matching model indices.
     */
    void updateMatches();

    /**
     * @brief Updates the label displaying the current match count (e.g. "1 of 5").
     */
    void updateCounterLabel();

    /**
     * @brief Navigates the selection to the specified match index.
     * @param model_index The match index to navigate to.
     */
    void navigateTo(qsizetype model_index);

    /**
     * @brief Expands parent nodes in the tree so the match is visible.
     * @param model_index The model index whose parents should be expanded.
     */
    void expandParents(const QModelIndex &model_index);

    /**
     * @brief Recursively collects all model indices within the tree.
     * @param parent The parent model index to start from.
     * @param out List to populate with model indices.
     */
    void collectIndices(const QModelIndex &parent, QList<QModelIndex> &out);

    /** @brief Pointer to the protocol tree. */
    ProtoTree *proto_tree_;

    /** @brief Line edit for entering search text. */
    SyntaxLineEdit *search_edit_;
    /** @brief Button to toggle case-sensitive search. */
    QToolButton *case_button_;
    /** @brief Button to toggle regular expression search. */
    QToolButton *regex_button_;
    /** @brief Button to toggle whole word search. */
    QToolButton *word_button_;
    /** @brief Label showing current match count and total matches. */
    QLabel *counter_label_;
    /** @brief Button to go to the previous match. */
    QToolButton *prev_button_;
    /** @brief Button to go to the next match. */
    QToolButton *next_button_;
    /** @brief Button to close the find bar. */
    QToolButton *close_button_;

    /** @brief Timer for debouncing search input. */
    QTimer *debounce_timer_;
    /** @brief Animation for showing and hiding the bar. */
    QPropertyAnimation *animation_;

    /** @brief State flag tracking if the bar is open. */
    bool is_open_;

    /** @brief Count of open bar instances. */
    static int open_instances_;

    /** @brief List of model indices that match the current search. */
    QList<QModelIndex> matches_;
    /** @brief The index of the currently active match in matches_. */
    qsizetype current_match_;
    /** @brief State flag for an invalid regular expression. */
    bool regex_invalid_;
    /** @brief The natural height of the find bar for animation purposes. */
    int natural_height_;
};

#endif // IN_PACKET_FIND_BAR_H