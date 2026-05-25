/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PREFERENCES_DIALOG_H
#define PREFERENCES_DIALOG_H

#include <config.h>

#include <epan/prefs.h>

#include <ui/qt/models/pref_models.h>
#include <ui/qt/models/pref_delegate.h>

#include "geometry_state_dialog.h"

class QComboBox;
class QAbstractButton;

namespace Ui {
class PreferencesDialog;
}

/**
 * @brief Dialog for configuring Wireshark preferences.
 */
class PreferencesDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a PreferencesDialog.
     * @param parent The parent widget.
     */
    explicit PreferencesDialog(QWidget *parent = 0);

    /**
     * @brief Destroys the PreferencesDialog.
     */
    ~PreferencesDialog();

    /**
     * @brief Show the preference pane corresponding to the a preference module name.
     * @param module_name A preference module name, e.g. the "name" parameter passed
     * to prefs_register_module or a protocol name.
     */
    void setPane(const QString module_name);

protected:
    /**
     * @brief Handles key press events within the dialog.
     * @param event The key press event.
     */
    void keyPressEvent(QKeyEvent *event) override;

    /**
     * @brief Handles the show event for the dialog.
     * @param evt The show event.
     */
    void showEvent(QShowEvent *evt) override;

private:
    /**
     * @brief Applies the current preference changes.
     */
    void apply();

    /**
     * @brief Resizes the splitter within the dialog.
     */
    void resizeSplitter();

    Ui::PreferencesDialog *pd_ui_; /**< Pointer to the user interface form elements. */

    QHash<QString, QWidget*> prefs_pane_to_item_; /**< Hash mapping preference pane names to their corresponding widgets. */

    PrefsModel model_; /**< The base preferences model. */
    AdvancedPrefsModel advancedPrefsModel_; /**< The model for advanced preferences. */
    AdvancedPrefDelegate advancedPrefsDelegate_; /**< The delegate for advanced preferences. */
    ModulePrefsModel modulePrefsModel_; /**< The model for module preferences. */
    bool saved_capture_no_extcap_; /**< Flag storing the saved state of the no-extcap capture preference. */

    QTimer *searchLineEditTimer; /**< Timer used to debounce search input. */
    QString searchLineEditText; /**< The current text in the search line edit. */

private slots:
    /**
     * @brief Selects the specified preference pane.
     * @param pane The name of the pane to select.
     */
    void selectPane(QString pane);

    /**
     * @brief Handles the display of the copy context menu.
     * @param pos The position to show the menu.
     */
    void handleCopyMenu(QPoint pos);

    /**
     * @brief Slot triggered to copy the selected item.
     */
    void copyActionTriggered();

    /**
     * @brief Slot triggered to copy the selected row.
     */
    void copyRowActionTriggered();

    /**
     * @brief Handles text editing in the advanced search line edit.
     * @param search_re The search regular expression string.
     */
    void on_advancedSearchLineEdit_textEdited(const QString &search_re);

    /**
     * @brief Handles toggling of the show changed values checkbox.
     * @param checked The new checked state.
     */
    void on_showChangedValuesCheckBox_toggled(bool checked);

    /**
     * @brief Handles the acceptance (OK) of the dialog button box.
     */
    void on_buttonBox_accepted();

    /**
     * @brief Handles the rejection (Cancel) of the dialog button box.
     */
    void on_buttonBox_rejected();

    /**
     * @brief Handles help requests from the dialog button box.
     */
    void on_buttonBox_helpRequested();

    /**
     * @brief Handles clicks on the dialog button box.
     * @param button The button that was clicked.
     */
    void on_buttonBox_clicked(QAbstractButton *button);

    /**
     * @brief Update search results from the advancedSearchLineEdit field
     *
     * This is performed separately from on_advancedSearchLineEdit_textEdited
     * to support debouncing.
     */
    void updateSearchLineEdit();
};

#endif // PREFERENCES_DIALOG_H
