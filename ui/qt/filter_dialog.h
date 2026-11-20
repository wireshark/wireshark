/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FILTER_DIALOG_H
#define FILTER_DIALOG_H

#include "geometry_state_dialog.h"

#include <ui/qt/models/filter_list_model.h>

#include <QStyledItemDelegate>
#include <QValidator>

class QItemSelection;
class CopyFromProfileButton;
class FilterTreeDelegate;
class ProfileInheritComboBox;

namespace Ui {
class FilterDialog;
}

/**
 * @brief A dialog for managing and editing capture filters, display filters, and display macros.
 */
class FilterDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    /**
     * @brief Defines the type of filter being managed by the dialog.
     */
    enum FilterType {
        CaptureFilter, /**< A capture filter. */
        DisplayFilter, /**< A display filter. */
        DisplayMacro   /**< A display macro. */
    };

    /**
     * @brief Constructs a new FilterDialog.
     * @param parent The parent widget, defaults to 0.
     * @param filter_type The type of filter this dialog will manage, defaults to CaptureFilter.
     * @param new_filter An optional initial filter string to populate, defaults to an empty string.
     */
    explicit FilterDialog(QWidget *parent = 0, FilterType filter_type = CaptureFilter, const QString new_filter = QString());

    /**
     * @brief Destroys the FilterDialog.
     */
    ~FilterDialog();

private:
    /** Pointer to the generated UI elements. */
    Ui::FilterDialog *ui;

    /** Model managing the list of filters. */
    FilterListModel * model_;

    /** The active filter type for this dialog. */
    enum FilterType filter_type_;

    /** Delegate used for editing items in the filter tree. */
    FilterTreeDelegate *filter_tree_delegate_;

    /** The configuration file name of the filters. */
    const char *filename_;

    /** The button copying the filters of another profile. */
    CopyFromProfileButton *copy_button_;

    /** Selects where the filters come from. */
    ProfileInheritComboBox *inherit_combo_;

    /**
     * @brief Shows the own file, and the parent profiles the filters are inherited from.
     */
    void updatePathLabel();

    /**
     * @brief Adds a new filter to the dialog's model.
     * @param name The name of the new filter.
     * @param filter The filter string.
     * @param start_editing True to immediately begin editing the new filter in the UI, defaults to false.
     */
    void addFilter(QString name, QString filter, bool start_editing = false);

private slots:
    /**
     * @brief Updates the states of dialog widgets based on current selections.
     */
    void updateWidgets();

    /**
     * @brief Slot triggered when the selected filter item changes.
     * @param selected The newly selected items.
     * @param deselected The previously selected items.
     */
    void selectionChanged(const QItemSelection &selected, const QItemSelection &deselected);

    /**
     * @brief Slot triggered when the button adding a filter is clicked.
     */
    void newClicked();

    /**
     * @brief Slot triggered when the button deleting the selected filters is clicked.
     */
    void deleteClicked();

    /**
     * @brief Slot triggered when the button copying the selected filter is clicked.
     */
    void copyClicked();

    /**
     * @brief Slot triggered when the button clearing the own filters is clicked.
     */
    void clearClicked();

    /**
     * @brief Slot triggered when another inherit mode is selected.
     * @param mode The new mode.
     */
    void inheritModeChanged(profile_inherit_e mode);

    /**
     * @brief Adds the filters of another profile.
     * @param filename The file of the other profile.
     */
    void copyFromProfile(QString filename);

    /**
     * @brief Slot triggered when the dialog is accepted.
     */
    void on_buttonBox_accepted();

    /**
     * @brief Slot triggered when help is requested from the button box.
     */
    void on_buttonBox_helpRequested();
};

/**
 * @brief Delegate for editing capture and display filters.
 */
class FilterTreeDelegate : public QStyledItemDelegate
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new FilterTreeDelegate.
     * @param parent The parent QObject.
     * @param filter_type The type of filter being edited.
     */
    FilterTreeDelegate(QObject *parent, FilterDialog::FilterType filter_type);

    /**
     * @brief Returns the size of an item, not making rows with the lock of an inherited entry taller.
     * @param option The style option for the item.
     * @param index The model index of the item.
     * @return The size of the item.
     */
    QSize sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const override;

    /**
     * @brief Creates the editor widget for a specific item.
     * @param parent The parent widget for the editor.
     * @param option The style options for the item.
     * @param index The model index of the item being edited.
     * @return A pointer to the created editor widget.
     */
    virtual QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option, const QModelIndex &index) const override;

    /**
     * @brief Sets the data in the editor from the model.
     * @param editor The editor widget.
     * @param index The model index containing the data.
     */
    virtual void setEditorData(QWidget *editor, const QModelIndex &index) const override;

private:
    /** The type of filter this delegate is configuring editors for. */
    FilterDialog::FilterType filter_type_;
};

/**
 * @brief A validator for filter strings used by the FilterDialog fields.
 *
 * Distinct from the FilterValidator base in ui/qt/models/: this one is local to
 * the saved-filters dialog. (When the dialog migrates onto FilterEdit in a later
 * stage, this can be retired in favour of the injected validators.)
 */
class DialogFilterValidator : public QValidator
{
public:
    explicit DialogFilterValidator(QObject *parent = NULL) : QValidator(parent) {}
    /**
     * @brief Validates the input filter string.
     * @param input The filter string to validate.
     * @param pos The cursor position.
     * @return The validation state (Acceptable, Intermediate, or Invalid).
     */
    virtual QValidator::State validate(QString & input, int & pos) const override;
};

/**
 * @brief A validator for macro names.
 */
class MacroNameValidator : public QValidator
{
public:
    explicit MacroNameValidator(QObject *parent = NULL) : QValidator(parent) {}
    /**
     * @brief Validates the input macro name.
     * @param input The macro name string to validate.
     * @param pos The cursor position.
     * @return The validation state.
     */
    virtual QValidator::State validate(QString & input, int & pos) const override;
};

#endif // FILTER_DIALOG_H
