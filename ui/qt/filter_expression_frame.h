/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FILTER_EXPRESSION_FRAME_H
#define FILTER_EXPRESSION_FRAME_H

#include "accordion_frame.h"

namespace Ui {
class FilterExpressionFrame;
}

/**
 * @brief An accordion frame for adding or editing filter expressions.
 */
class FilterExpressionFrame : public AccordionFrame
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new FilterExpressionFrame.
     * @param parent The parent widget, defaults to 0.
     */
    explicit FilterExpressionFrame(QWidget *parent = 0);

    /**
     * @brief Destroys the FilterExpressionFrame.
     */
    ~FilterExpressionFrame();

    /**
     * @brief Adds a new filter expression.
     * @param filter_text The text of the filter expression to add.
     */
    void addExpression(const QString filter_text);

    /**
     * @brief Edits an existing filter expression.
     * @param exprIdx The index of the expression to edit.
     */
    void editExpression(int exprIdx);

signals:
    /**
     * @brief Signal emitted to request showing the preferences dialog.
     * @param pane_name The name of the specific preferences pane to open.
     */
    void showPreferencesDialog(QString pane_name);

    /**
     * @brief Signal emitted when the list of filter expressions has changed.
     */
    void filterExpressionsChanged();

protected:
    /**
     * @brief Handles the event when the frame is shown.
     * @param event The show event.
     */
    virtual void showEvent(QShowEvent *event);

    /**
     * @brief Handles key press events within the frame.
     * @param event The key event.
     */
    virtual void keyPressEvent(QKeyEvent *event);

private:
    /** Pointer to the generated UI elements. */
    Ui::FilterExpressionFrame *ui;

    /** The index of the filter expression currently being edited. */
    int editExpression_;

private slots:
    /**
     * @brief Updates the enabled/disabled state of the frame's widgets.
     */
    void updateWidgets();

    /**
     * @brief Slot triggered when the preferences push button is clicked.
     */
    void on_filterExpressionPreferencesPushButton_clicked();

    /**
     * @brief Slot triggered when the text in the label line edit changes.
     */
    void on_labelLineEdit_textChanged(const QString);

    /**
     * @brief Slot triggered when the text in the display filter line edit changes.
     */
    void on_displayFilterLineEdit_textChanged(const QString);

    /**
     * @brief Slot triggered when the accepted button is clicked in the button box.
     */
    void on_buttonBox_accepted();

    /**
     * @brief Slot triggered when the rejected button is clicked in the button box.
     */
    void on_buttonBox_rejected();
};

#endif // FILTER_EXPRESSION_FRAME_H
