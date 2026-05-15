/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FIND_LINE_EDIT_H
#define FIND_LINE_EDIT_H

#include <QLineEdit>

namespace Ui {
class FindLineEdit;
}

/**
 * @brief A custom line edit for find operations, supporting regex and textual search.
 */
class FindLineEdit : public QLineEdit
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new FindLineEdit.
     * @param parent The parent widget, defaults to 0.
     */
    explicit FindLineEdit(QWidget *parent = 0) : QLineEdit(parent), use_regex_(false) { }

    /**
     * @brief Destroys the FindLineEdit.
     */
    ~FindLineEdit() { }

signals:
    /**
     * @brief Signal emitted when the regex search mode is toggled.
     * @param use_regex True if regular expressions should be used, false for plain text.
     */
    void useRegexFind(bool use_regex);

private slots:
    /**
     * @brief Sets the search mode to plain textual search.
     */
    void setUseTextual();

    /**
     * @brief Sets the search mode to regular expression search.
     */
    void setUseRegex();

private:
    /**
     * @brief Handles context menu events to provide custom options.
     * @param event The context menu event.
     */
    void contextMenuEvent(QContextMenuEvent *event);

    /**
     * @brief Handles key press events within the line edit.
     * @param event The key event.
     */
    void keyPressEvent(QKeyEvent *event);

    /**
     * @brief Validates the current input text, particularly for regex correctness.
     */
    void validateText();

    /** Flag indicating whether regular expression search is currently enabled. */
    bool use_regex_;
};

#endif // FIND_LINE_EDIT_H
