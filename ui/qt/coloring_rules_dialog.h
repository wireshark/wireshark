/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef COLORING_RULES_DIALOG_H
#define COLORING_RULES_DIALOG_H

#include "geometry_state_dialog.h"
#include "filter_action.h"

#include <ui/qt/models/coloring_rules_model.h>
#include <ui/qt/models/coloring_rules_delegate.h>

#include <QMap>

class QAbstractButton;

namespace Ui {
class ColoringRulesDialog;
}

/**
 * @brief A dialog for managing and configuring packet coloring rules.
 */
class ColoringRulesDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new ColoringRulesDialog.
     * @param parent The parent widget, defaults to 0.
     * @param add_filter An optional filter string to add initially, defaults to an empty string.
     */
    explicit ColoringRulesDialog(QWidget *parent = 0, QString add_filter = QString());

    /**
     * @brief Destroys the ColoringRulesDialog.
     */
    ~ColoringRulesDialog();

signals:
    /**
     * @brief Signal emitted when a filter action is requested.
     * @param filter The filter string.
     * @param action The specific action to perform.
     * @param type The type of the filter action.
     */
    void filterAction(QString filter, FilterAction::Action action, FilterAction::ActionType type);

protected:
    /**
     * @brief Handles the show event for the dialog.
     * @param event The show event object.
     */
    void showEvent(QShowEvent *event) override;

private slots:
    /**
     * @brief Copies coloring rules from a specified profile.
     * @param fileName The name of the profile file to copy from.
     */
    void copyFromProfile(QString fileName);

    /**
     * @brief Slot triggered when the color rule selection changes.
     * @param selected The newly selected items.
     * @param deselected The newly deselected items.
     */
    void colorRuleSelectionChanged(const QItemSelection &selected, const QItemSelection &deselected);

    /**
     * @brief Slot triggered when a color is changed.
     * @param foreground True if the foreground color changed, false for the background color.
     * @param cc The new color applied.
     */
    void colorChanged(bool foreground, const QColor &cc);

    /**
     * @brief Slot triggered when the foreground color push button is clicked.
     */
    void on_fGPushButton_clicked();

    /**
     * @brief Slot triggered when the background color push button is clicked.
     */
    void on_bGPushButton_clicked();

    /**
     * @brief Slot triggered when the display filter push button is clicked.
     */
    void on_displayFilterPushButton_clicked();

    /**
     * @brief Slot triggered when the new rule tool button is clicked.
     */
    void on_newToolButton_clicked();

    /**
     * @brief Slot triggered when the delete rule tool button is clicked.
     */
    void on_deleteToolButton_clicked();

    /**
     * @brief Slot triggered when the copy rule tool button is clicked.
     */
    void on_copyToolButton_clicked();

    /**
     * @brief Slot triggered when the clear tool button is clicked.
     */
    void on_clearToolButton_clicked();

    /**
     * @brief Slot triggered when a button in the button box is clicked.
     * @param button The abstract button that was clicked.
     */
    void on_buttonBox_clicked(QAbstractButton *button);

    /**
     * @brief Slot triggered when the dialog is accepted.
     */
    void on_buttonBox_accepted();

    /**
     * @brief Slot triggered when help is requested from the button box.
     */
    void on_buttonBox_helpRequested();

    /**
     * @brief Slot triggered when the row count in the model changes.
     */
    void rowCountChanged();

    /**
     * @brief Slot triggered when a field is marked as invalid.
     * @param index The model index of the invalid field.
     * @param errMessage The error message describing the issue.
     */
    void invalidField(const QModelIndex &index, const QString& errMessage);

    /**
     * @brief Slot triggered when a field is marked as valid.
     * @param index The model index of the valid field.
     */
    void validField(const QModelIndex &index);

    /**
     * @brief Slot triggered when a tree item is clicked.
     * @param index The model index of the clicked item.
     */
    void treeItemClicked(const QModelIndex &index);

private:
    /** Pointer to the generated UI elements. */
    Ui::ColoringRulesDialog *ui;

    /** Pointer to the import push button. */
    QPushButton *import_button_;

    /** Pointer to the export push button. */
    QPushButton *export_button_;

    /** The model managing the coloring rules. */
    ColoringRulesModel colorRuleModel_;

    /** The delegate for rendering and editing coloring rules. */
    ColoringRulesDelegate colorRuleDelegate_;

    /** A map storing error messages associated with specific model indices. */
    QMap<QModelIndex, QString> errors_;

    /**
     * @brief Checks for any unknown or invalid color filters.
     */
    void checkUnknownColorfilters();

    /**
     * @brief Sets the color of the foreground and background buttons based on the given index.
     * @param index The model index to retrieve colors from.
     */
    void setColorButtons(QModelIndex &index);

    /**
     * @brief Updates the hint label in the dialog.
     * @param idx The model index to update the hint for, defaults to an invalid QModelIndex.
     */
    void updateHint(QModelIndex idx = QModelIndex());

    /**
     * @brief Adds a new coloring rule to the model.
     * @param copy_from_current True to duplicate the currently selected rule, false to create a blank rule (defaults to false).
     */
    void addRule(bool copy_from_current = false);

    /**
     * @brief Initiates a color change for the currently selected rule.
     * @param foreground True to change the foreground color, false to change the background color (defaults to true).
     */
    void changeColor(bool foreground = true);

    /**
     * @brief Validates a given filter string.
     * @param filter The filter string to validate.
     * @param error Pointer to a string to store any validation error message.
     * @return True if the filter is valid, false otherwise.
     */
    bool isValidFilter(QString filter, QString *error);
};

#endif // COLORING_RULES_DIALOG_H
