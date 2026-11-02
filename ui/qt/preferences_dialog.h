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

    /**
     * @brief Switches the page navigation mode when the dialog is resized.
     * @param event The resize event.
     */
    void resizeEvent(QResizeEvent *event) override;

    /**
     * @brief Closes the page drawer on a click on the scrim or on Enter or
     * Escape in the tree, and keeps the drawer over the page area.
     * @param obj The watched object.
     * @param event The event.
     * @return true if the event was handled.
     */
    bool eventFilter(QObject *obj, QEvent *event) override;

private:
    /**
     * @brief Applies the current preference changes.
     * @param closing true if the dialog closes afterwards, in which case
     * the redissection is queued until the dialog is destroyed.
     */
    void apply(bool closing);

    /**
     * @brief Resizes the splitter within the dialog.
     */
    void resizeSplitter();

    /**
     * @brief Sets the page stack's minimum size to that of the current page.
     */
    void updatePageMinimumSize();

    /**
     * @brief Shrinks and moves the dialog so its frame fits the available screen area.
     */
    void fitToScreen();

    /**
     * @brief Returns the dialog width at which the page tree fits beside the widest page.
     * @return The width; only valid once showEvent() measured the tree and the pages.
     */
    int sideBySideWidth() const;

    /**
     * @brief Sizes a dialog that has no saved geometry for the side-by-side layout
     * with the tallest page unscrolled, and centers it over its parent again.
     */
    void applyDefaultSize();

    /**
     * @brief Switches to the compact navigation when the dialog is too narrow
     * to show the page tree beside the widest page, and back.
     */
    void updateNavigationMode();

    /**
     * @brief Moves the page tree out of the splitter (compact) or back into it.
     * @param compact true to hide the tree behind the Pages button.
     */
    void setCompactNavigation(bool compact);

    /**
     * @brief Shows the current page and its group in the navigation row.
     */
    void updateBreadcrumb();

    /**
     * @brief Places the scrim and the tree over the page area.
     */
    void layoutDrawer();

    Ui::PreferencesDialog *pd_ui_; /**< Pointer to the user interface form elements. */

    QHash<QString, QWidget*> prefs_pane_to_item_; /**< Hash mapping preference pane names to their corresponding widgets. */

    PrefsModel model_; /**< The base preferences model. */
    AdvancedPrefsModel advancedPrefsModel_; /**< The model for advanced preferences. */
    AdvancedPrefDelegate advancedPrefsDelegate_; /**< The delegate for advanced preferences. */
    ModulePrefsModel modulePrefsModel_; /**< The model for module preferences. */
    int prefs_tree_width_ = 0; /**< Minimum width of the page tree, set by resizeSplitter(). */
    int widest_page_width_ = 0; /**< Widest minimum width of all pages, from the stack layout in showEvent(). */
    bool compact_navigation_ = false; /**< Whether the page tree is moved out of the splitter. */
    bool geometry_fitted_ = false; /**< Whether showEvent fitted the dialog to the screen. */
    bool geometry_restored_ = false; /**< Whether loadGeometry() applied a saved geometry. */
    QWidget *nav_scrim_ = nullptr; /**< Dims the page while the page tree is shown over it. */

    QTimer *searchLineEditTimer; /**< Timer used to debounce search input. */
    QString searchLineEditText; /**< The current text in the search line edit. */

private slots:
    /**
     * @brief Shows or hides the page tree over the page area in compact mode.
     * @param open true to show it; follows the Pages button's checked state.
     */
    void setDrawerOpen(bool open);

    /**
     * @brief Closes the drawer when focus moves to a widget outside it.
     * @param old The widget that lost focus.
     * @param now The widget that gained focus.
     */
    void applicationFocusChanged(QWidget *old, QWidget *now);

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
