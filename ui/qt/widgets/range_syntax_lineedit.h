/** @file
 *
 * Delegates for editing preferences.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef RANGE_SYNTAX_LINEEDIT_H
#define RANGE_SYNTAX_LINEEDIT_H

#include <ui/qt/widgets/syntax_line_edit.h>

#include <QWidget>

/**
 * @brief SyntaxLineEdit specialisation that validates a packet range expression
 *        (e.g. "1-5,7,10-20") against a configurable upper bound, colouring
 *        the field to reflect validity.
 */
class RangeSyntaxLineEdit : public SyntaxLineEdit
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a RangeSyntaxLineEdit with no maximum range set.
     * @param parent Optional parent widget.
     */
    explicit RangeSyntaxLineEdit(QWidget *parent = 0);

    /**
     * @brief Sets the inclusive upper bound for range validation.
     *
     * Any range expression referencing a value above @p max will be treated
     * as invalid.
     *
     * @param max Maximum allowable packet/frame number in a valid range expression.
     */
    void setMaxRange(unsigned int max);

public slots:
    /**
     * @brief Validates @p range against the current maximum and updates the
     *        field's syntax-highlighting state accordingly.
     * @param range Range expression string to validate (e.g. "1-5,8,12-20").
     */
    void checkRange(QString range);

private:
    unsigned int maxRange_; /**< Inclusive upper bound used when validating range expressions. */
};

#endif // RANGE_SYNTAX_LINEEDIT_H
