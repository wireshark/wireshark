/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DISPLAY_FILTER_EXPRESSION_DIALOG_H
#define DISPLAY_FILTER_EXPRESSION_DIALOG_H

#include "config.h"

#include <epan/ftypes/ftypes.h>

#include "geometry_state_dialog.h"

#include <QFutureWatcher>

class QTreeWidgetItem;
struct true_false_string;
struct _value_string;
struct _val64_string;

namespace Ui {
class DisplayFilterExpressionDialog;
}

/**
 * @brief A dialog to assist users in building and selecting display filter expressions.
 */
class DisplayFilterExpressionDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new DisplayFilterExpressionDialog.
     * @param parent The parent widget, defaults to 0.
     */
    explicit DisplayFilterExpressionDialog(QWidget *parent = 0);

    /**
     * @brief Destroys the DisplayFilterExpressionDialog.
     */
    ~DisplayFilterExpressionDialog();

signals:
    /**
     * @brief Signal emitted to insert a constructed display filter string into the target editor.
     * @param filter The display filter string.
     */
    void insertDisplayFilter(const QString &filter);

private slots:
    /**
     * @brief Slot to handle adding a tree item asynchronously (if QPromise is used).
     * @param result The result identifier or payload.
     */
    void addTreeItem(int result);

    /**
     * @brief Slot to populate the field tree widget with available protocols and fields.
     */
    void fillTree();

    /**
     * @brief Slot to update the state of the dialog widgets based on user selection.
     */
    void updateWidgets();

    /**
     * @brief Slot triggered when the selection in the field tree widget changes.
     */
    void on_fieldTreeWidget_itemSelectionChanged();

    /**
     * @brief Slot triggered when the selection in the relation list widget changes.
     */
    void on_relationListWidget_itemSelectionChanged();

    /**
     * @brief Slot triggered when the selection in the enum list widget changes.
     */
    void on_enumListWidget_itemSelectionChanged();

    /**
     * @brief Slot triggered when the search text is edited.
     * @param search_re The new search text or regular expression string.
     */
    void on_searchLineEdit_textChanged(const QString &search_re);

    /**
     * @brief Slot triggered when the dialog is accepted.
     */
    void on_buttonBox_accepted();

    /**
     * @brief Slot triggered when help is requested from the button box.
     */
    void on_buttonBox_helpRequested();

private:
    /** Watcher for asynchronous operations returning a single tree widget item. */
    QFutureWatcher<QTreeWidgetItem *> *watcher;

    /** Pointer to the generated UI elements. */
    Ui::DisplayFilterExpressionDialog *ui;

    /**
     * @brief Fills the enum list widget with boolean values.
     * @param tfs Pointer to the true/false string structure.
     */
    void fillEnumBooleanValues(const struct true_false_string *tfs);

    /**
     * @brief Fills the enum list widget with integer values.
     * @param vals Pointer to the value string structure.
     * @param base The numerical base for formatting (e.g., 10, 16).
     */
    void fillEnumIntValues(const struct _value_string *vals, int base);

    /**
     * @brief Fills the enum list widget with 64-bit integer values.
     * @param vals64 Pointer to the 64-bit value string structure.
     * @param base The numerical base for formatting (e.g., 10, 16).
     */
    void fillEnumInt64Values(const struct _val64_string *vals64, int base);

    /**
     * @brief Fills the enum list widget with range values.
     * @param rvals Pointer to the range string structure.
     */
    void fillEnumRangeValues(const struct _range_string *rvals);

    /** The field type enum of the currently selected field. */
    enum ftenum ftype_;

    /** The name identifier of the currently selected field. */
    const char *field_;

    /** A prefix applied to value labels. */
    QString value_label_pfx_;
};

#endif // DISPLAY_FILTER_EXPRESSION_DIALOG_H
