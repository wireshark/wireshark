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

class PreferencesDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    explicit PreferencesDialog(QWidget *parent = 0);
    ~PreferencesDialog();

    /**
     * Show the preference pane corresponding to the a preference module name.
     * @param module_name A preference module name, e.g. the "name" parameter passed
     * to prefs_register_module or a protocol name.
     */
    void setPane(const QString module_name);

protected:
    void showEvent(QShowEvent *evt);

private:
    void apply();

    Ui::PreferencesDialog *pd_ui_;

    QHash<QString, QWidget*> prefs_pane_to_item_;

    PrefsModel model_;
    AdvancedPrefsModel advancedPrefsModel_;
    AdvancedPrefDelegate advancedPrefsDelegate_;
    ModulePrefsModel modulePrefsModel_;
    bool saved_capture_no_extcap_;

    QTimer *searchLineEditTimer;
    QString searchLineEditText;

private slots:
    void selectPane(QString pane);
    void on_advancedSearchLineEdit_textEdited(const QString &search_re);
    void on_showChangedValuesCheckBox_toggled(bool checked);

    void on_buttonBox_accepted();
    void on_buttonBox_rejected();
    void on_buttonBox_helpRequested();
    void on_buttonBox_clicked(QAbstractButton *button);

    /**
     * Update search results from the advancedSearchLineEdit field
     *
     * This is performed separately from on_advancedSearchLineEdit_textEdited
     * to support debouncing.
     */
    void updateSearchLineEdit();
};

#endif // PREFERENCES_DIALOG_H
